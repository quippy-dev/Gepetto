import json

def _get(obj, key, default=None):
    """Safely get a value from either a dict or an object."""
    if isinstance(obj, dict):
        return obj.get(key, default)
    return getattr(obj, key, default)

def add_result_to_inputs(input_items, tc, result):
    """
    Appends a tool result to a list of input items for the OpenAI Responses API.
    """
    call_id = _get(tc, "id")

    if isinstance(result, (dict, list)):
        output = json.dumps(result, ensure_ascii=False)
    else:
        output = str(result)

    input_items.append({
        "type": "function_call_output",
        "call_id": call_id or "",
        "output": output,
    })
