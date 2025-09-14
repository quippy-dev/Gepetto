import json
import hashlib
import ida_bytes
import ida_kernwin
import ida_idaapi
import ida_nalt
import ida_segment
import ida_funcs
import ida_name
import ida_xref
import idautils
import idaapi
import ida_strlist

from gepetto.ida.tools.tools import add_result_to_messages


# -----------------------------------------------------------------------------
# Tool call handlers
# -----------------------------------------------------------------------------

def handle_search_tc(tc, messages):
    """
    Handler for the 'search' tool. Searches for a specific text or hex pattern
    and returns matching EAs. (Targeted queries, not enumeration.)
    """
    try:
        args = json.loads(getattr(tc.function, "arguments", "") or "{}")
    except Exception:
        args = {}

    text = args.get("text")
    hex_pattern = args.get("hex")
    case_sensitive = bool(args.get("case_sensitive", False))

    try:
        result = search(text=text, hex=hex_pattern, case_sensitive=case_sensitive)
    except Exception as ex:
        result = {"ok": False, "error": str(ex)}

    add_result_to_messages(messages, tc, result)

# -----------------------------------------------------------------------------

def handle_list_strings_tc(tc, messages):
    """
    Handler for the 'list_strings' tool. Enumerates discovered strings with
    pagination and filters.
    """
    try:
        args = json.loads(getattr(tc.function, "arguments", "") or "{}")
    except Exception:
        args = {}

    try:
        result = list_strings(
            limit=int(args.get("limit", 200)),
            offset=int(args.get("offset", 0)),
            min_len=int(args.get("min_len", 4)),
            encodings=args.get("encodings"),
            segments=args.get("segments"),
            include_xrefs=bool(args.get("include_xrefs", False)),
            include_text=bool(args.get("include_text", True)),
            max_text_bytes=int(args.get("max_text_bytes", 256)),
            return_addresses_only=bool(args.get("return_addresses_only", False)),
            sort_by=(args.get("sort_by") or "ea").lower(),
        )
    except Exception as ex:
        result = {"ok": False, "error": str(ex)}

    add_result_to_messages(messages, tc, result)

# -----------------------------------------------------------------------------

def handle_list_strings_filter_tc(tc, messages):
    """Handler for the 'list_strings_filter' tool (MCP parity)."""
    try:
        args = json.loads(getattr(tc.function, "arguments", "") or "{}")
    except Exception:
        args = {}

    try:
        result = list_strings_filter(
            offset=int(args.get("offset", 0)),
            count=int(args.get("count", 100)),
            filter_text=str(args.get("filter", "")),
        )
    except Exception as ex:
        result = {"ok": False, "error": str(ex)}

    add_result_to_messages(messages, tc, result)

# -----------------------------------------------------------------------------
# Shared snapshot utilities
# -----------------------------------------------------------------------------

def _snapshot_strings_and_segments():
    """Runs on UI thread: safely snapshot strings and segments for background use.

    Notes:
      - Assumes caller wrapped this in ida_kernwin.execute_sync(..., MFF_WRITE)
        because build_strlist() mutates IDA state.
      - Always returns a 2-tuple: (strings: list[dict], segs: list[tuple[int,int]]).
    """
    try:
        # Rebuild the Strings list so we don't iterate a stale/empty view.
        try:
            ida_strlist.build_strlist()
        except Exception:
            pass  # best-effort; continue even if rebuild fails

        string_view = idautils.Strings()
        string_view.refresh()  # pick up the freshly-built list

        strings = []
        for si in string_view:
            ea = int(si.ea)
            text = str(si)
            stype = int(si.strtype)  # IDA string type code
            seg = ida_segment.getseg(ea)
            seg_name = ida_segment.get_segm_name(seg) if seg else ""
            strings.append({
                "ea": ea,
                "text": text,
                "len": len(text),
                "stype": stype,
                "segment": seg_name or "",
            })

        segs = []
        for s in idautils.Segments():
            try:
                seg = ida_segment.getseg(s)
                if seg:
                    segs.append((int(seg.start_ea), int(seg.end_ea)))
            except Exception:
                continue

        return strings, segs

    except Exception:
        raise

# -----------------------------------------------------------------------------

def _ui_snapshot_wrapper():
    """Executes snapshot on the UI thread and returns a dict with 'strings' and 'segs'."""
    snap = {}
    def _ui_snapshot():
        res = _snapshot_strings_and_segments()
        if not isinstance(res, tuple) or len(res) != 2:
            res = ([], [])
        snap["strings"], snap["segs"] = res
        return 1
    ida_kernwin.execute_sync(_ui_snapshot, ida_kernwin.MFF_WRITE)
    return snap

# -----------------------------------------------------------------------------

def _strtype_to_label(stype: int) -> str:
    """Map IDA strtype enum to a coarse encoding label."""
    if stype == getattr(ida_nalt, "STRTYPE_C_16", -1):
        return "utf16"
    if stype == getattr(ida_nalt, "STRTYPE_C_32", -1):
        return "utf32"
    if stype == getattr(ida_nalt, "STRTYPE_C", -1):
        return "ascii"
    if stype == getattr(ida_nalt, "STRTYPE_PASCAL", -1):
        return "ascii"
    # fallback: most strings are 1-byte
    return "ascii"


# -----------------------------------------------------------------------------

def _iter_xrefs_to(ea: int, max_items: int = 64):
    """Best-effort, bounded xref collection."""
    out = []
    xb = ida_xref.xrefblk_t()
    if xb.first_to(ea, ida_xref.XREF_FAR):
        count = 0
        while True:
            out.append(int(xb.frm))
            count += 1
            if count >= max_items or not xb.next_to():
                break
    return out

# -----------------------------------------------------------------------------
# Public tool implementations
# -----------------------------------------------------------------------------

def search(text: str | None = None, hex: str | None = None, case_sensitive: bool = False) -> dict:
    """
    Targeted search for text or hex patterns. Returns matching EAs.
    """
    out: dict = {"ok": False, "eas": [], "error": None}

    if not text and not hex:
        out["error"] = "Either text or hex must be provided"
        return out

    snap = _ui_snapshot_wrapper()
    strings = snap.get("strings", [])
    segs = snap.get("segs", [])

    matches: list[int] = []

    # Text search: operate on the pre-extracted string list (no UI calls).
    if text:
        q = text if case_sensitive else text.casefold()
        for x in strings:
            hay = x["text"] if case_sensitive else x["text"].casefold()
            if q in hay:
                matches.append(int(x["ea"]))

    # Hex search: segment-bounded search to avoid scanning the whole VA space.
    # IDA 9.x port: ida_search.find_binary removed; use ida_bytes.find_bytes (see 'ida_search' removed functions, and 'ida_bytes' added functions in the porting guide).
    if hex:
        flags = ida_bytes.BIN_SEARCH_FORWARD | ida_bytes.BIN_SEARCH_NOSHOW
        for (start, end) in segs:
            ea = ida_bytes.find_bytes(
                hex,                  # pattern string, same value previously passed to find_binary
                start,                # range_start
                range_end=end,        # restrict to the current segment
                flags=flags,
                radix=16              # interpret pattern as hex string
            )
            while ea != ida_idaapi.BADADDR and ea < end:
                matches.append(int(ea))
                # advance at least one byte to avoid infinite loop
                ea = ida_bytes.find_bytes(
                    hex,
                    ea + 1,
                    range_end=end,
                    flags=flags,
                    radix=16
                )
            ida_kernwin.process_ui_events()

    if matches:
        matches = sorted(set(matches))

    out["eas"] = matches
    out["ok"] = True
    return out

# -----------------------------------------------------------------------------

def list_strings(
        limit: int = 200,
        offset: int = 0,
        min_len: int = 4,
        encodings: list[str] | None = None,
        segments: list[str] | None = None,
        include_xrefs: bool = False,
        include_text: bool = True,
        max_text_bytes: int = 256,
        return_addresses_only: bool = False,
        sort_by: str = "ea",
) -> dict:
    """
    Enumerate discovered strings with pagination and filters.

    Returns:
      {
        "ok": bool,
        "error": str|None,
        "total": int,
        "next_offset": int|None,
        "items": [ ... ]  # either EAs or dicts with metadata
      }
    """
    out = {"ok": False, "error": None, "total": 0, "next_offset": None, "items": []}

    snap = _ui_snapshot_wrapper()
    items = snap.get("strings", [])

    # Filters
    if min_len > 1:
        items = [x for x in items if x["len"] >= min_len]

    if encodings:
        encset = {e.lower() for e in encodings}
        items = [x for x in items if _strtype_to_label(x["stype"]) in encset]

    if segments:
        segset = {s.lower() for s in segments}
        items = [x for x in items if (x["segment"].lower() in segset)]

    # Sorting
    if sort_by == "len":
        items.sort(key=lambda x: (x["len"], x["ea"]))
    elif sort_by == "segment":
        items.sort(key=lambda x: (x["segment"], x["ea"]))
    else:
        items.sort(key=lambda x: x["ea"])

    total = len(items)
    out["total"] = total

    # Pagination
    start = max(0, int(offset))
    end = min(total, start + max(1, int(limit)))
    page = items[start:end]

    if end < total:
        out["next_offset"] = end

    # Build payload
    results = []
    for x in page:
        if return_addresses_only:
            results.append(int(x["ea"]))
            continue

        entry = {
            "ea": int(x["ea"]),
            "len": int(x["len"]),
            "segment": x["segment"],
            "encoding": _strtype_to_label(x["stype"]),
        }

        if include_text:
            # Truncate text to keep payload small and provide a digest for dedup.
            t = x["text"]
            clipped = t.encode(errors="replace")[:max_text_bytes]
            try:
                clipped_text = clipped.decode(errors="replace")
            except Exception:
                clipped_text = t[:max_text_bytes]
            entry["text"] = clipped_text
            entry["text_truncated"] = (len(t.encode(errors="replace")) > len(clipped))
            entry["sha1"] = hashlib.sha1(t.encode(errors="replace")).hexdigest()

        if include_xrefs:
            entry["xrefs_to"] = _iter_xrefs_to(x["ea"])

        results.append(entry)

    out["items"] = results
    out["ok"] = True
    return out

# -----------------------------------------------------------------------------

def _compile_filter(pattern: str):
    """Return (callable) predicate for matching string text.

    - '/regex/' => treat as regex; optional trailing '/i' enables IGNORECASE
    - otherwise: case-insensitive substring match
    """
    if isinstance(pattern, str) and len(pattern) >= 2 and pattern.startswith('/'):
        last = pattern.rfind('/')
        if last > 0:
            body = pattern[1:last]
            flags = pattern[last+1:].lower()
            import re
            re_flags = re.IGNORECASE if 'i' in flags else 0
            try:
                rx = re.compile(body, re_flags)
                return lambda s: bool(rx.search(s or ""))
            except Exception:
                pass
    q = (pattern or "").casefold()
    return lambda s: q in (s or "").casefold()


def list_strings_filter(offset: int, count: int, filter_text: str) -> dict:
    """
    MCP-parity helper: list strings with a simple filter and pagination.

    Returns: { ok, data: [ {address, length, string} ], next_offset }
    """
    snap = _ui_snapshot_wrapper()
    items = snap.get("strings", [])

    pred = _compile_filter(filter_text or "")
    rows = []
    for x in items:
        t = x.get("text") or ""
        if pred(t):
            rows.append({
                "address": f"{int(x['ea']):#x}",
                "length": int(x.get("len", len(t))),
                "string": t,
            })

    total = len(rows)
    if count == 0:
        end = total
    else:
        end = min(total, max(0, offset) + max(0, count))
    page = rows[offset:end]
    next_offset = end if end < total else None

    return {"ok": True, "data": page, "next_offset": next_offset}
