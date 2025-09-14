import json
from typing import Dict, List, Set

import ida_funcs
import ida_gdl
import ida_name
import ida_xref

from gepetto.ida.utils.ida9_utils import run_on_main_thread, parse_ea
from gepetto.ida.tools.tools import add_result_to_messages


def handle_summarize_function_tc(tc, messages):
    try:
        args = json.loads(getattr(tc.function, "arguments", "") or "{}")
    except Exception:
        args = {}
    try:
        include_edges = bool(args.get("include_edges", False))
        max_preview = int(args.get("max_preview", 10) or 10)
        max_blocks = int(args.get("max_blocks", 512) or 512)
        result = summarize_function(
            args.get("function_address") or args.get("ea"),
            include_edges=include_edges,
            max_preview=max_preview,
            max_blocks=max_blocks,
        )
    except Exception as ex:
        result = {"ok": False, "error": str(ex)}
    add_result_to_messages(messages, tc, result)


def _func_info(ea: int):
    def _do():
        f = ida_funcs.get_func(ea)
        if not f:
            return None
        name = ida_name.get_ea_name(f.start_ea) or ""
        return {"ea": int(f.start_ea), "name": name, "size": int(f.end_ea - f.start_ea)}
    return run_on_main_thread(_do, write=False)


def _flowchart(start_ea: int, need_edges: bool = False, max_blocks: int = 512):
    blocks = []
    edges = []
    cond_blocks = 0

    def _do():
        nonlocal cond_blocks
        f = ida_funcs.get_func(start_ea)
        if not f:
            return 0
        fc = ida_gdl.FlowChart(f)
        count = 0
        for b in fc:
            if count >= max_blocks:
                break
            count += 1
            try:
                bid = int(b.id)
                blocks.append({
                    "block_id": bid,
                    "start": int(b.start_ea),
                    "end": int(b.end_ea),
                })
                # Count successors to estimate conditional branches
                succ_ids = [int(s.id) for s in b.succs()]
                if len(succ_ids) >= 2:
                    cond_blocks += 1
                if need_edges:
                    for sid in succ_ids:
                        edges.append({"from": bid, "to": sid})
            except Exception:
                continue
        return 1

    run_on_main_thread(_do, write=False)
    return blocks, edges, cond_blocks


def _callees(start_ea: int) -> List[Dict]:
    out = []
    seen: Set[int] = set()
    counts: Dict[int, int] = {}

    def _do():
        f = ida_funcs.get_func(start_ea)
        if not f:
            return 0
        xb = ida_xref.xrefblk_t()
        ea = int(f.start_ea)
        end = int(f.end_ea)
        cur = ea
        while cur < end:
            if xb.first_from(cur, ida_xref.XREF_FAR):
                while True:
                    if xb.iscode and xb.type in (ida_xref.fl_CN, ida_xref.fl_CF):
                        tgt = int(xb.to)
                        counts[tgt] = counts.get(tgt, 0) + 1
                        if tgt not in seen:
                            seen.add(tgt)
                            out.append({"ea": tgt, "name": ida_name.get_ea_name(tgt) or "", "count": 0})
                    if not xb.next_from():
                        break
            try:
                import ida_bytes
                nxt = ida_bytes.get_item_end(cur)
                if not isinstance(nxt, int) or nxt <= cur:
                    nxt = cur + 1
                cur = nxt
            except Exception:
                cur += 1
        return 1

    run_on_main_thread(_do, write=False)
    # Fill counts
    for it in out:
        it["count"] = int(counts.get(it["ea"], 0))
    # Sort by count desc, then by name
    out.sort(key=lambda d: (d.get("count", 0), d.get("name", "")), reverse=True)
    return out


def _preview(function_ea: int, max_items: int = 10) -> Dict:
    """Compose a light preview: top strings and immediates referenced by the function."""
    try:
        from gepetto.ida.tools.function_scan import get_function_strings, get_function_immediates
        strings = get_function_strings(f"{function_ea:#x}").get("strings", [])
        imms = get_function_immediates(f"{function_ea:#x}").get("items", [])
        # Clip and simplify
        strings = strings[:max_items]
        flat_imms: List[int] = []
        for it in imms:
            flat_imms.extend(it.get("values", []) or [])
        # Dedup, keep order
        seen = set()
        uniq_imms = []
        for v in flat_imms:
            if v in seen:
                continue
            seen.add(v)
            uniq_imms.append(v)
        uniq_imms = uniq_imms[:max_items]
        return {"strings": strings, "immediates": uniq_imms}
    except Exception:
        return {"strings": [], "immediates": []}


def summarize_function(function_address: str, include_edges: bool = False, max_preview: int = 10, max_blocks: int = 512) -> Dict:
    if not function_address:
        return {"ok": False, "error": "function_address is required"}
    ea = parse_ea(function_address)
    fi = _func_info(ea)
    if not fi:
        return {"ok": False, "error": "EA is not inside a function"}
    blocks, edges, cond_blocks = _flowchart(fi["ea"], need_edges=include_edges, max_blocks=max_blocks)
    callees = _callees(fi["ea"])
    preview = _preview(fi["ea"], max_items=max_preview)
    metrics = {
        "block_count": len(blocks),
        "branch_blocks": int(cond_blocks),
        "unique_callees": len(callees),
        "call_sites": int(sum(max(1, c.get("count", 0)) for c in callees)),
        # Keep preview counts minimal to avoid oversized payloads
        "string_refs": int(len(preview.get("strings", []))) if isinstance(preview.get("strings"), list) else 0,
        "immediates": int(len(preview.get("immediates", []))) if isinstance(preview.get("immediates"), list) else 0,
    }
    # Keep only top N callees by count for actionability
    top_callees = callees[:10]
    out = {"ok": True, "function": fi, "blocks": blocks, "callees": top_callees, "metrics": metrics, "preview": preview}
    if include_edges:
        out["edges"] = edges
    return out
